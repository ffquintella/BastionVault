//! Tauri commands backing the GUI Plugins admin page.
//!
//! Both connection modes are supported:
//!
//! * **Embedded** — dispatches directly against the open vault's
//!   barrier-decrypted storage + the in-process `WasmRuntime`.
//! * **Remote** — forwards each call to `/v1/sys/plugins/*` on the
//!   connected server via the shared `state.remote_client`. The
//!   server emits its own audit on the HTTP path, so the embedded-side
//!   `emit_sys_audit` calls below are skipped in this branch to avoid
//!   double-logging.
//!
//! Each command starts with a `state.mode` check. Response shapes
//! match between modes so the frontend's `api.ts` doesn't need to
//! know which mode it's in.

use base64::Engine;
use bastion_vault::plugins::{
    metrics::{snapshot_all, PluginMetricsSnapshot},
    ConfigField, ConfigStore, InvokeOutcome, PluginCatalog, PluginManifest, WasmRuntime,
    DEFAULT_FUEL, DEFAULT_MEMORY_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::{AppState, VaultMode};

// ── Remote-mode HTTP helpers ──────────────────────────────────────
//
// In remote mode each command forwards to a `/v1/sys/plugins/*`
// endpoint via the `Client` the connect flow stashed on AppState.
// The token is attached per-request via `with_token`.

/// Issue a request to the remote server, returning the raw status +
/// response body. The Client is configured with `http_status_as_error
/// (false)`, so 4xx/5xx surface here as an Ok with the failing status
/// — callers decide whether the status counts as success (e.g. 404 →
/// `None` for `plugins_get`, or always-error for `plugins_list`).
async fn remote_raw(
    state: &State<'_, AppState>,
    method: &str,
    path: &str,
    body: Option<Map<String, Value>>,
) -> Result<(u16, Value), CommandError> {
    let client_guard = state.remote_client.lock().await;
    let client = client_guard
        .as_ref()
        .ok_or("Not connected to remote server")?
        .clone();
    drop(client_guard);

    let token = state.token.lock().await.clone().unwrap_or_default();
    let bound = client.with_token(&token);
    let url = format!("{}/{}", bound.api_prefix(), path);

    let resp = match method {
        "GET" => bound.request_read(url),
        "POST" => bound.request_write(url, body),
        "PUT" => bound.request_put(url, body),
        "DELETE" => bound.request_delete(url, body),
        other => return Err(CommandError::from(format!("unsupported method `{other}`"))),
    }
    .map_err(|e| CommandError::from(format!("{e}")))?;

    Ok((resp.response_status, resp.response_data.unwrap_or(Value::Null)))
}

/// Like [`remote_raw`] but turns any non-2xx status into a
/// `CommandError` populated from the server's `{"error": "..."}`
/// envelope.
async fn remote_call(
    state: &State<'_, AppState>,
    method: &str,
    path: &str,
    body: Option<Map<String, Value>>,
) -> Result<Value, CommandError> {
    let (status, json) = remote_raw(state, method, path, body).await?;
    if (200..300).contains(&status) {
        Ok(json)
    } else {
        Err(CommandError::from(remote_error_message(status, &json)))
    }
}

/// Like [`remote_call`] but maps a `404 Not Found` to `Ok(None)`.
/// Used by lookup commands whose Tauri signatures already model
/// "missing" with `Option<_>`.
async fn remote_call_opt(
    state: &State<'_, AppState>,
    method: &str,
    path: &str,
    body: Option<Map<String, Value>>,
) -> Result<Option<Value>, CommandError> {
    let (status, json) = remote_raw(state, method, path, body).await?;
    if status == 404 {
        return Ok(None);
    }
    if (200..300).contains(&status) {
        Ok(Some(json))
    } else {
        Err(CommandError::from(remote_error_message(status, &json)))
    }
}

fn remote_error_message(status: u16, json: &Value) -> String {
    json.as_object()
        .and_then(|o| o.get("error").and_then(|v| v.as_str()))
        .map(String::from)
        .unwrap_or_else(|| format!("HTTP {status}"))
}

fn decode_json<T: serde::de::DeserializeOwned>(v: Value, what: &str) -> Result<T, CommandError> {
    serde_json::from_value(v).map_err(|e| CommandError::from(format!("decode {what}: {e}")))
}

async fn is_remote(state: &State<'_, AppState>) -> bool {
    matches!(*state.mode.lock().await, VaultMode::Remote)
}

// ── Public command surface ────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PluginListResult {
    pub plugins: Vec<PluginManifest>,
}

/// Read the publisher allowlist. Returns `name → hex(public_key)`.
#[tauri::command]
pub async fn plugins_get_publishers(
    state: State<'_, AppState>,
) -> CmdResult<BTreeMap<String, String>> {
    if is_remote(&state).await {
        let json = remote_call(&state, "GET", "sys/plugins/publishers", None).await?;
        let pubs = json
            .get("publishers")
            .cloned()
            .unwrap_or(Value::Object(Map::new()));
        return decode_json(pubs, "publishers");
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let allow =
        bastion_vault::plugins::verifier::PublisherAllowlist::load(core.barrier.as_storage())
            .await
            .map_err(CommandError::from)?;
    Ok(allow.keys.into_iter().collect())
}

/// Replace the publisher allowlist. Takes the full map; the caller
/// (GUI) reads the current map, applies its add/remove, and submits
/// the result. Mirrors the PUT /v1/sys/plugins/publishers shape.
#[tauri::command]
pub async fn plugins_set_publishers(
    state: State<'_, AppState>,
    publishers: BTreeMap<String, String>,
) -> CmdResult<()> {
    // Validate hex + length up front so a typo doesn't break verify
    // later. ML-DSA-65 PK is 1952 bytes / 3904 hex chars. We do this
    // client-side regardless of mode so the operator gets the same
    // immediate feedback whether they're hitting an embedded vault
    // or a remote server.
    for (name, pk_hex) in &publishers {
        if name.is_empty() {
            return Err("publisher name cannot be empty".into());
        }
        let bytes = hex_decode(pk_hex).ok_or_else(|| {
            CommandError::from(format!("publisher `{name}` public key is not valid hex"))
        })?;
        if bytes.len() != bv_crypto::ML_DSA_65_PUBLIC_KEY_LEN {
            return Err(CommandError::from(format!(
                "publisher `{name}` public key must be {} bytes, got {}",
                bv_crypto::ML_DSA_65_PUBLIC_KEY_LEN,
                bytes.len()
            )));
        }
    }

    if is_remote(&state).await {
        let body = json!({ "keys": publishers })
            .as_object()
            .cloned();
        remote_call(&state, "PUT", "sys/plugins/publishers", body).await?;
        return Ok(());
    }

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let allow = bastion_vault::plugins::verifier::PublisherAllowlist {
        keys: publishers.into_iter().collect(),
    };
    allow
        .save(core.barrier.as_storage())
        .await
        .map_err(CommandError::from)?;
    Ok(())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi as u8) << 4) | lo as u8);
    }
    Some(out)
}

/// Read the engine's `accept_unsigned` flag. Default-closed when the
/// key is missing, matching `verifier::read_accept_unsigned`.
///
/// The HTTP API has no dedicated GET for this flag, so in remote mode
/// we read it off the combined publishers endpoint, which already
/// returns it alongside the allowlist.
#[tauri::command]
pub async fn plugins_get_accept_unsigned(state: State<'_, AppState>) -> CmdResult<bool> {
    if is_remote(&state).await {
        let json = remote_call(&state, "GET", "sys/plugins/publishers", None).await?;
        let v = json
            .get("accept_unsigned")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        return Ok(v);
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    bastion_vault::plugins::verifier::read_accept_unsigned(core.barrier.as_storage())
        .await
        .map_err(CommandError::from)
}

/// Flip the `accept_unsigned` flag. Logged at WARN by the verifier
/// when set to `true`.
#[tauri::command]
pub async fn plugins_set_accept_unsigned(
    state: State<'_, AppState>,
    on: bool,
) -> CmdResult<bool> {
    if is_remote(&state).await {
        let body = json!({ "accept_unsigned": on }).as_object().cloned();
        let resp = remote_call(&state, "PUT", "sys/plugins/accept_unsigned", body).await?;
        let v = resp
            .get("accept_unsigned")
            .and_then(|v| v.as_bool())
            .unwrap_or(on);
        return Ok(v);
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    bastion_vault::plugins::verifier::write_accept_unsigned(core.barrier.as_storage(), on)
        .await
        .map_err(CommandError::from)?;
    Ok(on)
}

#[tauri::command]
pub async fn plugins_list(state: State<'_, AppState>) -> CmdResult<PluginListResult> {
    if is_remote(&state).await {
        let json = remote_call(&state, "GET", "sys/plugins", None).await?;
        let plugins_v = json
            .get("plugins")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        let plugins: Vec<PluginManifest> = decode_json(plugins_v, "plugin manifests")?;
        return Ok(PluginListResult { plugins });
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let catalog = PluginCatalog::new();
    let plugins = catalog
        .list(core.barrier.as_storage())
        .await
        .map_err(CommandError::from)?;
    Ok(PluginListResult { plugins })
}

#[tauri::command]
pub async fn plugins_get(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<Option<PluginManifest>> {
    if is_remote(&state).await {
        match remote_call_opt(&state, "GET", &format!("sys/plugins/{name}"), None).await? {
            None => return Ok(None),
            Some(json) => {
                let manifest_v = json.get("manifest").cloned().unwrap_or(Value::Null);
                if manifest_v.is_null() {
                    return Ok(None);
                }
                let m: PluginManifest = decode_json(manifest_v, "plugin manifest")?;
                return Ok(Some(m));
            }
        }
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let catalog = PluginCatalog::new();
    let manifest = catalog
        .get_manifest(core.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from)?;
    Ok(manifest)
}

#[derive(Debug, Deserialize)]
pub struct PluginRegisterInput {
    pub manifest: PluginManifest,
    /// Base64 of the WASM binary. The frontend reads the `.wasm` file
    /// the operator picked, base64-encodes, and ships the payload here.
    pub binary_b64: String,
}

#[tauri::command]
pub async fn plugins_register(
    state: State<'_, AppState>,
    input: PluginRegisterInput,
) -> CmdResult<PluginManifest> {
    if is_remote(&state).await {
        // The HTTP register endpoint takes manifest + binary_b64 in the
        // same shape the Tauri command does, so we just forward the
        // payload as-is. base64 validation happens server-side; we
        // sanity-check decodability locally for parity with the
        // embedded path's pre-flight error.
        base64::engine::general_purpose::STANDARD
            .decode(input.binary_b64.as_bytes())
            .map_err(|_| "binary_b64 not valid base64")?;
        let body = json!({
            "manifest": input.manifest,
            "binary_b64": input.binary_b64,
        })
        .as_object()
        .cloned();
        let resp = remote_call(&state, "POST", "sys/plugins", body).await?;
        let manifest_v = resp.get("manifest").cloned().unwrap_or(Value::Null);
        let manifest: PluginManifest = decode_json(manifest_v, "registered manifest")?;
        return Ok(manifest);
    }

    let binary = base64::engine::general_purpose::STANDARD
        .decode(input.binary_b64.as_bytes())
        .map_err(|_| "binary_b64 not valid base64")?;

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);

    let catalog = PluginCatalog::new();
    let outcome = catalog
        .put(core_arc.barrier.as_storage(), &input.manifest, &binary)
        .await
        .map_err(CommandError::from);

    let token = state.token.lock().await.clone().unwrap_or_default();
    let mut audit_body = serde_json::Map::new();
    audit_body.insert(
        "name".to_string(),
        serde_json::Value::String(input.manifest.name.clone()),
    );
    audit_body.insert(
        "version".to_string(),
        serde_json::Value::String(input.manifest.version.clone()),
    );
    audit_body.insert(
        "size".to_string(),
        serde_json::Value::Number(input.manifest.size.into()),
    );
    let err_str = match &outcome {
        Err(e) => Some(format!("{e:?}")),
        _ => None,
    };
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &token,
        "sys/plugins/register",
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        err_str.as_deref(),
    )
    .await;

    outcome?;
    Ok(input.manifest)
}

#[tauri::command]
pub async fn plugins_delete(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    if is_remote(&state).await {
        remote_call(&state, "DELETE", &format!("sys/plugins/{name}"), None).await?;
        return Ok(());
    }

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);

    let catalog = PluginCatalog::new();
    let outcome = catalog
        .delete(core_arc.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from);

    let token = state.token.lock().await.clone().unwrap_or_default();
    let mut audit_body = serde_json::Map::new();
    audit_body.insert("name".to_string(), serde_json::Value::String(name.clone()));
    let err_str = match &outcome {
        Err(e) => Some(format!("{e:?}")),
        _ => None,
    };
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &token,
        &format!("sys/plugins/{name}"),
        bastion_vault::logical::Operation::Delete,
        Some(audit_body),
        err_str.as_deref(),
    )
    .await;

    outcome
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginInvokeResult {
    /// "success" | "plugin_error"
    pub status: String,
    pub plugin_status_code: i32,
    pub fuel_consumed: u64,
    pub response_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginConfigResult {
    pub schema: Vec<ConfigField>,
    pub values: BTreeMap<String, String>,
}

#[tauri::command]
pub async fn plugins_get_config(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PluginConfigResult> {
    if is_remote(&state).await {
        let json = remote_call(&state, "GET", &format!("sys/plugins/{name}/config"), None).await?;
        return decode_json(json, "plugin config");
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let catalog = PluginCatalog::new();
    let manifest = catalog
        .get_manifest(core.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from)?
        .ok_or("plugin not found")?;
    let store = ConfigStore::new();
    let values = store
        .get_redacted(core.barrier.as_storage(), &manifest)
        .await
        .map_err(CommandError::from)?;
    Ok(PluginConfigResult {
        schema: manifest.config_schema,
        values,
    })
}

#[tauri::command]
pub async fn plugins_set_config(
    state: State<'_, AppState>,
    name: String,
    values: BTreeMap<String, String>,
) -> CmdResult<()> {
    if is_remote(&state).await {
        let body = json!({ "values": values }).as_object().cloned();
        remote_call(&state, "PUT", &format!("sys/plugins/{name}/config"), body).await?;
        return Ok(());
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);

    let catalog = PluginCatalog::new();
    let manifest = catalog
        .get_manifest(core_arc.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from)?
        .ok_or("plugin not found")?;
    let store = ConfigStore::new();
    let outcome = store
        .put(core_arc.barrier.as_storage(), &manifest, values)
        .await
        .map_err(CommandError::from);

    let token = state.token.lock().await.clone().unwrap_or_default();
    let mut audit_body = serde_json::Map::new();
    audit_body.insert("name".into(), serde_json::Value::String(name.clone()));
    let err_str = match &outcome {
        Err(e) => Some(format!("{e:?}")),
        _ => None,
    };
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &token,
        &format!("sys/plugins/{name}/config"),
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        err_str.as_deref(),
    )
    .await;
    outcome
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginVersionsResult {
    pub versions: Vec<PluginManifest>,
    pub active: Option<String>,
}

#[tauri::command]
pub async fn plugins_versions(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PluginVersionsResult> {
    if is_remote(&state).await {
        let json = remote_call(&state, "GET", &format!("sys/plugins/{name}/versions"), None).await?;
        return decode_json(json, "plugin versions");
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let catalog = PluginCatalog::new();
    let versions = catalog
        .list_versions(core.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from)?;
    let active = catalog
        .get_active_version(core.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from)?;
    Ok(PluginVersionsResult { versions, active })
}

#[tauri::command]
pub async fn plugins_activate_version(
    state: State<'_, AppState>,
    name: String,
    version: String,
) -> CmdResult<()> {
    if is_remote(&state).await {
        remote_call(
            &state,
            "POST",
            &format!("sys/plugins/{name}/versions/{version}/activate"),
            None,
        )
        .await?;
        return Ok(());
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);

    let catalog = PluginCatalog::new();
    let outcome = catalog
        .set_active(core_arc.barrier.as_storage(), &name, &version)
        .await
        .map_err(CommandError::from);

    if outcome.is_ok() {
        if let Ok(cache) = bastion_vault::plugins::ModuleCache::shared() {
            cache.invalidate(&name);
        }
    }

    let token = state.token.lock().await.clone().unwrap_or_default();
    let mut audit_body = serde_json::Map::new();
    audit_body.insert("name".into(), serde_json::Value::String(name.clone()));
    audit_body.insert("version".into(), serde_json::Value::String(version.clone()));
    let err_str = match &outcome {
        Err(e) => Some(format!("{e:?}")),
        _ => None,
    };
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &token,
        &format!("sys/plugins/{name}/versions/{version}/activate"),
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        err_str.as_deref(),
    )
    .await;
    outcome
}

#[tauri::command]
pub async fn plugins_delete_version(
    state: State<'_, AppState>,
    name: String,
    version: String,
) -> CmdResult<()> {
    if is_remote(&state).await {
        remote_call(
            &state,
            "DELETE",
            &format!("sys/plugins/{name}/versions/{version}"),
            None,
        )
        .await?;
        return Ok(());
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let catalog = PluginCatalog::new();
    catalog
        .delete_version(core.barrier.as_storage(), &name, &version)
        .await
        .map_err(CommandError::from)?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PluginReloadResult {
    pub name: String,
    pub active_version: String,
    pub sha256: String,
    pub cache_entries_evicted: usize,
}

#[tauri::command]
pub async fn plugins_reload(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PluginReloadResult> {
    if is_remote(&state).await {
        let json = remote_call(&state, "POST", &format!("sys/plugins/{name}/reload"), None).await?;
        // The server response carries an extra `drained_via` key the
        // Tauri shape doesn't model; serde's default behavior drops
        // unknown fields so we can decode straight into our struct.
        return decode_json(json, "plugin reload result");
    }
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);

    let catalog = PluginCatalog::new();
    let record = catalog
        .get(core_arc.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from)?
        .ok_or("plugin not found")?;
    let cache = bastion_vault::plugins::ModuleCache::shared().map_err(|e| format!("{e}"))?;
    let evicted = cache.invalidate(&name);

    let token = state.token.lock().await.clone().unwrap_or_default();
    let mut audit_body = serde_json::Map::new();
    audit_body.insert("name".into(), serde_json::Value::String(name.clone()));
    audit_body.insert(
        "active_version".into(),
        serde_json::Value::String(record.manifest.version.clone()),
    );
    audit_body.insert(
        "cache_entries_evicted".into(),
        serde_json::Value::Number(evicted.into()),
    );
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &token,
        &format!("sys/plugins/{name}/reload"),
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        None,
    )
    .await;

    Ok(PluginReloadResult {
        name,
        active_version: record.manifest.version,
        sha256: record.manifest.sha256,
        cache_entries_evicted: evicted,
    })
}

#[tauri::command]
pub async fn plugins_invoke(
    state: State<'_, AppState>,
    name: String,
    input_b64: Option<String>,
    fuel: Option<u64>,
) -> CmdResult<PluginInvokeResult> {
    if is_remote(&state).await {
        // Server happily accepts an empty/missing input_b64; mirror
        // the embedded validation so a bad base64 fails locally
        // before we burn a round-trip.
        if let Some(b64) = &input_b64 {
            if !b64.is_empty() {
                base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .map_err(|_| "input_b64 not valid base64")?;
            }
        }
        let mut body = Map::new();
        if let Some(b64) = input_b64.clone() {
            body.insert("input_b64".to_string(), Value::String(b64));
        }
        if let Some(f) = fuel {
            body.insert("fuel".to_string(), Value::Number(f.into()));
        }
        let body = if body.is_empty() { None } else { Some(body) };
        let json = remote_call(&state, "POST", &format!("sys/plugins/{name}/invoke"), body).await?;
        return decode_json(json, "plugin invoke result");
    }

    let input = match input_b64 {
        Some(b64) if !b64.is_empty() => base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| "input_b64 not valid base64")?,
        _ => Vec::new(),
    };

    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let core_arc: std::sync::Arc<bastion_vault::core::Core> = std::sync::Arc::clone(&*core);
    drop(vault_guard);

    let catalog = PluginCatalog::new();
    let record = catalog
        .get(core_arc.barrier.as_storage(), &name)
        .await
        .map_err(CommandError::from)?
        .ok_or("plugin not found")?;

    let config_store = ConfigStore::new();
    let config = config_store
        .get(core_arc.barrier.as_storage(), &record.manifest.name)
        .await
        .unwrap_or_default();

    let outcome = match record.manifest.runtime {
        bastion_vault::plugins::RuntimeKind::Wasm => {
            let fuel = fuel
                .unwrap_or(DEFAULT_FUEL)
                .min(DEFAULT_FUEL.saturating_mul(10));
            let runtime = WasmRuntime::with_budgets(fuel, DEFAULT_MEMORY_BYTES)
                .map_err(|e| format!("{e}"))?;
            runtime
                .invoke_with_config(
                    &record.manifest,
                    &record.binary,
                    &input,
                    Some(core_arc.clone()),
                    config,
                )
                .await
                .map_err(|e| format!("{e}"))
        }
        bastion_vault::plugins::RuntimeKind::Process => {
            let runtime = bastion_vault::plugins::ProcessRuntime::new();
            runtime
                .invoke_with_config(
                    &record.manifest,
                    &record.binary,
                    &input,
                    Some(core_arc.clone()),
                    config,
                )
                .await
                .map_err(|e| format!("{e}"))
        }
    };

    let token = state.token.lock().await.clone().unwrap_or_default();
    let mut audit_body = serde_json::Map::new();
    audit_body.insert("name".to_string(), serde_json::Value::String(name.clone()));
    audit_body.insert(
        "input_size".to_string(),
        serde_json::Value::Number(input.len().into()),
    );
    let err_str = match &outcome {
        Err(e) => Some(e.clone()),
        Ok(_) => None,
    };
    bastion_vault::audit::emit_sys_audit(
        &core_arc,
        &token,
        &format!("sys/plugins/{name}/invoke"),
        bastion_vault::logical::Operation::Write,
        Some(audit_body),
        err_str.as_deref(),
    )
    .await;

    let output = outcome.map_err(CommandError::from)?;
    let (status, plugin_status_code) = match output.outcome {
        InvokeOutcome::Success => ("success".to_string(), 0),
        InvokeOutcome::PluginError(c) => ("plugin_error".to_string(), c),
    };
    Ok(PluginInvokeResult {
        status,
        plugin_status_code,
        fuel_consumed: output.fuel_consumed,
        response_b64: base64::engine::general_purpose::STANDARD.encode(&output.response),
    })
}


/// Read a file from the user's local filesystem and return its bytes
/// base64-encoded. Used by plugin pages (e.g. PKI Import XCA) that
/// accept a local file but invoke a plugin which may run on a remote
/// server — the file lives on the client, so the GUI ships the bytes
/// inline rather than passing a `file_path` the server can't resolve.
///
/// No mode gate: this only touches the local filesystem and never
/// reaches the vault, so it's safe in either embedded or remote mode.
#[tauri::command]
pub async fn read_local_file_b64(path: String) -> CmdResult<String> {
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| CommandError::from(format!("read {path}: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
}


// ── Phase 5.12 — per-plugin metrics for the GUI ──

#[derive(Debug, serde::Serialize)]
pub struct PluginMetricsListResult {
    pub snapshots: Vec<PluginMetricsSnapshot>,
}

/// Snapshot every plugin counter the host has recorded since boot.
/// Each entry projects the per-plugin slice of the Prometheus
/// families backing `bvault_plugin_invokes_total`,
/// `bvault_plugin_fuel_consumed_total`, and
/// `bvault_plugin_invoke_duration_seconds`.
///
/// Embedded mode reads the in-process registry directly. Remote mode
/// has no JSON-shaped metrics endpoint — the server's `/sys/metrics`
/// is Prometheus text — so this returns an empty list. The desktop
/// metrics panel's empty state ("No invokes recorded since boot") is
/// the right surfacing for that.
#[tauri::command]
pub async fn plugins_metrics(state: State<'_, AppState>) -> CmdResult<PluginMetricsListResult> {
    if is_remote(&state).await {
        return Ok(PluginMetricsListResult { snapshots: Vec::new() });
    }
    Ok(PluginMetricsListResult { snapshots: snapshot_all() })
}
