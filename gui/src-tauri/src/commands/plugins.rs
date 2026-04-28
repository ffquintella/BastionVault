//! Tauri commands backing the GUI Plugins admin page.
//!
//! Embedded mode dispatches directly against the open vault's
//! barrier-decrypted storage + the in-process `WasmRuntime`. Remote
//! mode uses the equivalent `/v1/sys/plugins/*` HTTP endpoints; we
//! don't wrap those here because the GUI's `useEmbeddedOrRemote` glue
//! routes through the existing `Sys` API client when in remote mode.
//! For now the plugin admin tab is embedded-only; remote-mode parity
//! lands when the GUI's auth/remote layer learns about the plugin
//! endpoints.

use base64::Engine;
use bastion_vault::plugins::{
    metrics::{snapshot_all, PluginMetricsSnapshot},
    ConfigField, ConfigStore, InvokeOutcome, PluginCatalog, PluginManifest, WasmRuntime,
    DEFAULT_FUEL, DEFAULT_MEMORY_BYTES,
};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct PluginListResult {
    pub plugins: Vec<PluginManifest>,
}

#[tauri::command]
pub async fn plugins_list(state: State<'_, AppState>) -> CmdResult<PluginListResult> {
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

#[derive(Debug, Serialize)]
pub struct PluginInvokeResult {
    /// "success" | "plugin_error"
    pub status: String,
    pub plugin_status_code: i32,
    pub fuel_consumed: u64,
    pub response_b64: String,
}

#[derive(Debug, Serialize)]
pub struct PluginConfigResult {
    pub schema: Vec<ConfigField>,
    pub values: BTreeMap<String, String>,
}

#[tauri::command]
pub async fn plugins_get_config(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PluginConfigResult> {
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

#[derive(Debug, Serialize)]
pub struct PluginVersionsResult {
    pub versions: Vec<PluginManifest>,
    pub active: Option<String>,
}

#[tauri::command]
pub async fn plugins_versions(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PluginVersionsResult> {
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

#[derive(Debug, Serialize)]
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
#[tauri::command]
pub async fn plugins_metrics(_state: State<'_, AppState>) -> CmdResult<PluginMetricsListResult> {
    Ok(PluginMetricsListResult { snapshots: snapshot_all() })
}
