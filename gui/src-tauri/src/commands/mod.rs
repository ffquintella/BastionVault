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
    let namespace = state.active_namespace.lock().await.clone();
    dispatch_with_token_ns(state, operation, path, body, &token, namespace.as_deref()).await
}

/// Variant of [`make_request`] pinned to the root namespace, ignoring the
/// session's active namespace. The `sys/namespaces` CRUD surface is always
/// addressed from the root's view (paths are full slash-delimited), so its
/// requests must not pick up the namespace the switcher just selected —
/// otherwise switching into a child scopes `list_namespaces` to that child,
/// returning its (empty) children and hiding every sibling.
pub async fn make_request_root(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> CmdResult<Option<JsonResponse>> {
    let token = state.token.lock().await.clone().unwrap_or_default();
    dispatch_with_token_ns(state, operation, path, body, &token, None).await
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
    dispatch_with_token_ns(state, operation, path, body, token, None).await
}

/// Variant of [`dispatch_with_token`] that also scopes the request to a
/// namespace (multi-tenancy). `None`/empty targets the root namespace.
pub async fn dispatch_with_token_ns(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
    token: &str,
    namespace: Option<&str>,
) -> CmdResult<Option<JsonResponse>> {
    let backend_guard = state.backend.lock().await;
    let backend = backend_guard
        .as_ref()
        .ok_or("No vault open or remote server connected")?
        .clone();
    drop(backend_guard);

    backend
        .handle_with_namespace(operation, &path, body, token, namespace)
        .await
        .map_err(CommandError::from)
}

/// Append the pagination cursor and page size to a `<list>-info` path.
///
/// Both travel in the query string rather than a body: these endpoints are
/// **reads** (paging a listing has to stay available to a read-only policy)
/// and a GET body does not survive the HTTP boundary. `bv_logical`'s query
/// allowlist lifts `after` and `limit` back into the request on arrival.
///
/// An empty `after` or a zero `limit` is omitted rather than sent, so the
/// server applies its own default page size.
pub fn paginated_path(base: &str, after: Option<String>, limit: Option<u64>) -> String {
    let mut query: Vec<String> = Vec::new();
    if let Some(a) = after.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
        query.push(format!("after={a}"));
    }
    if let Some(n) = limit.filter(|n| *n > 0) {
        query.push(format!("limit={n}"));
    }
    match query.is_empty() {
        true => base.to_string(),
        false => format!("{base}?{}", query.join("&")),
    }
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
pub mod connect_mfa;
pub mod fido2_native;
/// Windows-only: the OS WebAuthn platform API that `fido2_native` delegates
/// its ceremonies to. See that module's docs for why raw HID cannot work here.
#[cfg(windows)]
pub mod fido2_windows;
pub mod ssh_security_key;
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
pub mod profile;
pub mod namespaces;
pub mod notifications;
pub mod dos;
pub mod resources;
pub mod rustion;
pub mod secrets;
pub mod ssh;
pub mod sso_admin;
pub mod totp;
pub mod system;
pub mod users;
pub mod yubikey;
