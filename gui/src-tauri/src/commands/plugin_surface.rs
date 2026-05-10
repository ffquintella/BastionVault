//! Plugin Extensibility v1 — Tauri commands for the GUI's
//! plugin-surface integration.
//!
//! Three commands cover the full client-side surface flow:
//!
//! * [`plugin_surfaces_refresh`] — fetch `active-surfaces`, write the
//!   cache, return the bundle to the frontend.
//! * [`plugin_surface_asset`] — fetch one client asset by content
//!   hash, going through the cache.
//! * [`plugin_surface_dispatch`] — resolve a surface `{op, path}`
//!   binding (with `{mount}` and form-field substitution), then
//!   dispatch through the existing backend trait. Lets the generic
//!   surface renderer issue arbitrary plugin operations without
//!   each plugin needing its own Tauri command.

use std::path::PathBuf;
use std::sync::Arc;

use bv_client::{Backend, Operation, SurfaceCache};
use bv_plugin_surface::ActiveSurfaceBundle;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::{Manager, Runtime, State};

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

// ── Cache resolution ─────────────────────────────────────────────────

/// Resolve (and lazily initialise) the per-vault surface cache.
///
/// We hash the active backend's identity into a stable per-vault
/// directory so two vaults sharing `dirs::cache` don't collide. The
/// hash inputs are operator-visible: the `RemoteProfile` address (or
/// `embedded:<vault-id>` for embedded mode) and the active token
/// holder's entity ID.
///
/// Returning a `(cache, vault_id)` tuple keeps the per-call hash
/// recompute cheap — the resulting `SurfaceCache` is just a typed
/// `PathBuf`, so cloning is allocation of a single `String`.
async fn resolve_cache<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &State<'_, AppState>,
) -> Result<SurfaceCache, CommandError> {
    let mut guard = state.plugin_surface_cache.lock().await;
    if let Some(c) = guard.as_ref() {
        return Ok(c.clone());
    }
    let base: PathBuf = app
        .path()
        .cache_dir()
        .map_err(|e| CommandError::from(format!("could not resolve cache_dir: {e}")))?
        .join("com.bastionvault.gui")
        .join("plugins");
    // Vault identity: prefer the configured remote address; fall
    // back to a local marker. Token entity ID isn't always available
    // pre-login, so we key on connection identity here — sufficient
    // because login replays through the same backend instance.
    let mode = state.mode.lock().await.clone();
    let identifier = match mode {
        crate::state::VaultMode::Remote => {
            let prof = state.remote_profile.lock().await;
            prof.as_ref()
                .map(|p| p.address.clone())
                .unwrap_or_else(|| "remote:unknown".into())
        }
        crate::state::VaultMode::Embedded => "embedded:default".into(),
    };
    let vault_id = bv_client::vault_id_for(&identifier, "");
    let cache = SurfaceCache::new(base, &vault_id);
    *guard = Some(cache.clone());
    Ok(cache)
}

/// Drop the cached `SurfaceCache` handle so the next refresh
/// resolves it fresh — used by the connect/disconnect path when
/// the operator switches vaults. Not yet wired into the disconnect
/// flow (Phase 5 follow-up); `#[allow(dead_code)]` keeps the
/// build clean until then.
#[allow(dead_code)]
pub async fn clear_cache_handle(state: &State<'_, AppState>) {
    *state.plugin_surface_cache.lock().await = None;
}

async fn current_backend(state: &State<'_, AppState>) -> Result<Arc<dyn Backend>, CommandError> {
    let g = state.backend.lock().await;
    g.as_ref()
        .cloned()
        .ok_or_else(|| CommandError::from("No vault open or remote server connected"))
}

async fn current_token(state: &State<'_, AppState>) -> String {
    state.token.lock().await.clone().unwrap_or_default()
}

// ── Refresh ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PluginSurfacesResult {
    pub bundle: ActiveSurfaceBundle,
}

/// Fetch the aggregated active-surface bundle, going through the
/// per-vault cache. Frontend calls this on login and after a
/// surface-published event.
#[tauri::command]
pub async fn plugin_surfaces_refresh<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
) -> CmdResult<PluginSurfacesResult> {
    let cache = resolve_cache(&app, &state).await?;
    let backend = current_backend(&state).await?;
    let token = current_token(&state).await;
    let bundle = bv_client::refresh(&*backend, &cache, &token)
        .await
        .map_err(CommandError::from)?;
    Ok(PluginSurfacesResult { bundle })
}

// ── Asset fetch ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PluginSurfaceAssetArgs {
    pub plugin: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct PluginSurfaceAssetResult {
    /// Base64-encoded asset bytes. Returns `None` when the asset is
    /// not known to the server (404) — the renderer treats that as
    /// "skip the form-hook gracefully".
    pub bytes_b64: Option<String>,
}

#[tauri::command]
pub async fn plugin_surface_asset<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: State<'_, AppState>,
    args: PluginSurfaceAssetArgs,
) -> CmdResult<PluginSurfaceAssetResult> {
    use base64::Engine;
    let cache = resolve_cache(&app, &state).await?;
    let backend = current_backend(&state).await?;
    let token = current_token(&state).await;
    let bytes = bv_client::ensure_asset(
        &*backend,
        &cache,
        &args.plugin,
        &args.version,
        &args.sha256,
        &token,
    )
    .await
    .map_err(CommandError::from)?;
    let bytes_b64 = bytes.map(|b| base64::engine::general_purpose::STANDARD.encode(b));
    Ok(PluginSurfaceAssetResult { bytes_b64 })
}

// ── Dispatch (the generic surface → backend bridge) ──────────────────

#[derive(Debug, Deserialize)]
pub struct PluginSurfaceDispatchArgs {
    /// `"read" | "write" | "delete" | "list"` — mirrors the surface
    /// schema's `SurfaceOp`.
    pub op: String,
    /// Binding path with placeholders. `{mount}` is required (the
    /// caller has already resolved it from the active-surfaces
    /// bundle entry); `{<form_field>}` placeholders are substituted
    /// from `params`.
    pub path: String,
    /// Mount path the binding's `{mount}` placeholder resolves to.
    /// Surfaces declare bindings as `"{mount}/codes/{name}"`; the
    /// renderer passes the active mount here.
    pub mount: String,
    /// Form-field substitutions for `{name}`-style placeholders in
    /// the path. Only string-valued fields are substitutable; other
    /// shapes go in the body.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
    /// Optional JSON body for write operations.
    #[serde(default)]
    pub body: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize)]
pub struct PluginSurfaceDispatchResult {
    /// `data` field of the backend response, when present. The
    /// frontend renders this as a table / detail view.
    pub data: Option<Map<String, Value>>,
}

#[tauri::command]
pub async fn plugin_surface_dispatch(
    state: State<'_, AppState>,
    args: PluginSurfaceDispatchArgs,
) -> CmdResult<PluginSurfaceDispatchResult> {
    let op = match args.op.as_str() {
        "read" => Operation::Read,
        "write" => Operation::Write,
        "delete" => Operation::Delete,
        "list" => Operation::List,
        other => {
            return Err(CommandError::from(format!(
                "plugin_surface_dispatch: unknown op `{other}`"
            )));
        }
    };

    // Two-phase substitution: `{mount}` first (always), then any
    // `{<field>}` placeholders against `params`. Refuse any path
    // that still has unsubstituted placeholders or escapes the
    // mount root.
    let mut resolved = args.path.replace("{mount}", args.mount.trim_end_matches('/'));
    for (k, v) in &args.params {
        let needle = format!("{{{k}}}");
        resolved = resolved.replace(&needle, v);
    }
    if resolved.contains('{') || resolved.contains("..") {
        return Err(CommandError::from(format!(
            "plugin_surface_dispatch: unresolved placeholder or `..` in path `{resolved}`"
        )));
    }
    if !resolved.starts_with(args.mount.trim_end_matches('/')) {
        return Err(CommandError::from(format!(
            "plugin_surface_dispatch: resolved path `{resolved}` escapes mount `{}`",
            args.mount
        )));
    }

    let backend = current_backend(&state).await?;
    let token = current_token(&state).await;
    let resp = backend
        .handle(op, &resolved, args.body, &token)
        .await
        .map_err(CommandError::from)?;
    Ok(PluginSurfaceDispatchResult {
        data: resp.and_then(|r| r.data),
    })
}
