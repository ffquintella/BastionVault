//! Tauri commands bridging the desktop GUI to the cert-lifecycle
//! engine (Phases L5–L7 of the PKI key-management + lifecycle
//! initiative).
//!
//! Each command is a thin wrapper over `make_request` that routes to a
//! `<mount>/<route>` path under a caller-provided cert-lifecycle mount
//! and projects the response data into a GUI-friendly serializable
//! struct. The mount path is parameterised so multiple cert-lifecycle
//! mounts are addressable independently.

use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

async fn make_request(
    state: &State<'_, AppState>,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> Result<Option<bastion_vault::logical::Response>, CommandError> {
    let vault_guard = state.vault.lock().await;
    let vault = vault_guard.as_ref().ok_or("Vault not open")?;
    let core = vault.core.load();
    let token = state.token.lock().await.clone().unwrap_or_default();

    let mut req = Request::default();
    req.operation = operation;
    req.path = path;
    req.client_token = token;
    req.body = body;

    core.handle_request(&mut req).await.map_err(CommandError::from)
}

fn mount_prefix(mount: &str) -> String {
    let trimmed = mount.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "cert-lifecycle".to_string()
    } else {
        trimmed.to_string()
    }
}

fn data_to_map(resp: Option<bastion_vault::logical::Response>) -> Map<String, Value> {
    resp.and_then(|r| r.data).unwrap_or_default()
}

fn val_str(map: &Map<String, Value>, key: &str) -> String {
    map.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn val_u64(map: &Map<String, Value>, key: &str) -> u64 {
    map.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn val_i64(map: &Map<String, Value>, key: &str) -> i64 {
    map.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}

fn val_bool(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn val_str_array(map: &Map<String, Value>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

// ── Mount lifecycle ──────────────────────────────────────────────

#[derive(Serialize)]
pub struct CertLifecycleMountInfo {
    pub path: String,
    pub mount_type: String,
}

#[tauri::command]
pub async fn cert_lifecycle_list_mounts(
    state: State<'_, AppState>,
) -> CmdResult<Vec<CertLifecycleMountInfo>> {
    let resp = make_request(&state, Operation::Read, "sys/mounts".into(), None).await?;
    let map = data_to_map(resp);
    let mut out = Vec::new();
    for (path, info) in map.iter() {
        if let Some(t) = info.get("type").and_then(|v| v.as_str()) {
            if t == "cert-lifecycle" {
                out.push(CertLifecycleMountInfo {
                    path: path.clone(),
                    mount_type: t.to_string(),
                });
            }
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn cert_lifecycle_enable_mount(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let normalised = if path.ends_with('/') { path } else { format!("{path}/") };
    let mut body = Map::new();
    body.insert("type".into(), json!("cert-lifecycle"));
    make_request(&state, Operation::Write, format!("sys/mounts/{normalised}"), Some(body)).await?;
    Ok(())
}

// ── Targets ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CertLifecycleTarget {
    pub name: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub address: String,
    #[serde(default = "default_pki_mount")]
    pub pki_mount: String,
    pub role_ref: String,
    pub common_name: String,
    #[serde(default)]
    pub alt_names: Vec<String>,
    #[serde(default)]
    pub ip_sans: Vec<String>,
    #[serde(default)]
    pub ttl: String,
    #[serde(default = "default_key_policy")]
    pub key_policy: String,
    #[serde(default)]
    pub key_ref: String,
    #[serde(default = "default_renew_before")]
    pub renew_before: String,
    #[serde(default)]
    pub created_at: u64,
}

fn default_kind() -> String {
    "file".into()
}
fn default_pki_mount() -> String {
    "pki".into()
}
fn default_key_policy() -> String {
    "rotate".into()
}
fn default_renew_before() -> String {
    "168h".into()
}

#[tauri::command]
pub async fn cert_lifecycle_list_targets(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<Vec<String>> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::List, format!("{mount}/targets"), None).await?;
    Ok(val_str_array(&data_to_map(resp), "keys"))
}

#[tauri::command]
pub async fn cert_lifecycle_read_target(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<CertLifecycleTarget> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/targets/{name}"), None).await?;
    let map = data_to_map(resp);
    Ok(CertLifecycleTarget {
        name: val_str(&map, "name"),
        kind: val_str(&map, "kind"),
        address: val_str(&map, "address"),
        pki_mount: val_str(&map, "pki_mount"),
        role_ref: val_str(&map, "role_ref"),
        common_name: val_str(&map, "common_name"),
        alt_names: val_str_array(&map, "alt_names"),
        ip_sans: val_str_array(&map, "ip_sans"),
        ttl: val_str(&map, "ttl"),
        key_policy: val_str(&map, "key_policy"),
        key_ref: val_str(&map, "key_ref"),
        renew_before: val_str(&map, "renew_before"),
        created_at: val_u64(&map, "created_at"),
    })
}

#[tauri::command]
pub async fn cert_lifecycle_write_target(
    state: State<'_, AppState>,
    mount: String,
    target: CertLifecycleTarget,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let mut body = Map::new();
    body.insert("kind".into(), json!(target.kind));
    body.insert("address".into(), json!(target.address));
    body.insert("pki_mount".into(), json!(target.pki_mount));
    body.insert("role_ref".into(), json!(target.role_ref));
    body.insert("common_name".into(), json!(target.common_name));
    body.insert("alt_names".into(), json!(target.alt_names.join(",")));
    body.insert("ip_sans".into(), json!(target.ip_sans.join(",")));
    body.insert("ttl".into(), json!(target.ttl));
    body.insert("key_policy".into(), json!(target.key_policy));
    body.insert("key_ref".into(), json!(target.key_ref));
    body.insert("renew_before".into(), json!(target.renew_before));
    make_request(&state, Operation::Write, format!("{mount}/targets/{}", target.name), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn cert_lifecycle_delete_target(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    make_request(&state, Operation::Delete, format!("{mount}/targets/{name}"), None).await?;
    Ok(())
}

// ── State + manual renew ─────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct CertLifecycleState {
    pub name: String,
    pub current_serial: String,
    pub current_not_after: i64,
    pub last_renewal: u64,
    pub last_attempt: u64,
    pub last_error: String,
    pub next_attempt: u64,
    pub failure_count: u64,
}

#[tauri::command]
pub async fn cert_lifecycle_read_state(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<CertLifecycleState> {
    let mount = mount_prefix(&mount);
    let resp = make_request(&state, Operation::Read, format!("{mount}/state/{name}"), None).await?;
    let map = data_to_map(resp);
    Ok(CertLifecycleState {
        name: val_str(&map, "name"),
        current_serial: val_str(&map, "current_serial"),
        current_not_after: val_i64(&map, "current_not_after"),
        last_renewal: val_u64(&map, "last_renewal"),
        last_attempt: val_u64(&map, "last_attempt"),
        last_error: val_str(&map, "last_error"),
        next_attempt: val_u64(&map, "next_attempt"),
        failure_count: val_u64(&map, "failure_count"),
    })
}

#[derive(Serialize, Default)]
pub struct CertLifecycleRenewResult {
    pub name: String,
    pub serial_number: String,
    pub not_after: i64,
    pub delivered_to: String,
    pub delivery_kind: String,
    pub delivery_note: String,
}

#[tauri::command]
pub async fn cert_lifecycle_renew(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<CertLifecycleRenewResult> {
    let mount = mount_prefix(&mount);
    let resp = make_request(
        &state,
        Operation::Write,
        format!("{mount}/renew/{name}"),
        Some(Map::new()),
    )
    .await?;
    let map = data_to_map(resp);
    Ok(CertLifecycleRenewResult {
        name: val_str(&map, "name"),
        serial_number: val_str(&map, "serial_number"),
        not_after: val_i64(&map, "not_after"),
        delivered_to: val_str(&map, "delivered_to"),
        delivery_kind: val_str(&map, "delivery_kind"),
        delivery_note: val_str(&map, "delivery_note"),
    })
}

// ── Scheduler config ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CertLifecycleSchedulerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tick")]
    pub tick_interval_seconds: u64,
    /// Read-side: present-on-write only, never echoed back. The GUI
    /// surfaces `client_token_set` to the user instead.
    #[serde(default)]
    pub client_token: String,
    #[serde(default)]
    pub client_token_set: bool,
    #[serde(default = "default_base_backoff")]
    pub base_backoff_seconds: u64,
    #[serde(default = "default_max_backoff")]
    pub max_backoff_seconds: u64,
}

fn default_tick() -> u64 {
    30
}
fn default_base_backoff() -> u64 {
    60
}
fn default_max_backoff() -> u64 {
    3600
}

#[tauri::command]
pub async fn cert_lifecycle_read_scheduler_config(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<CertLifecycleSchedulerConfig> {
    let mount = mount_prefix(&mount);
    let resp =
        make_request(&state, Operation::Read, format!("{mount}/scheduler/config"), None).await?;
    let map = data_to_map(resp);
    Ok(CertLifecycleSchedulerConfig {
        enabled: val_bool(&map, "enabled"),
        tick_interval_seconds: val_u64(&map, "tick_interval_seconds"),
        client_token: String::new(),
        client_token_set: val_bool(&map, "client_token_set"),
        base_backoff_seconds: val_u64(&map, "base_backoff_seconds"),
        max_backoff_seconds: val_u64(&map, "max_backoff_seconds"),
    })
}

#[tauri::command]
pub async fn cert_lifecycle_write_scheduler_config(
    state: State<'_, AppState>,
    mount: String,
    config: CertLifecycleSchedulerConfig,
) -> CmdResult<()> {
    let mount = mount_prefix(&mount);
    let mut body = Map::new();
    body.insert("enabled".into(), json!(config.enabled));
    body.insert("tick_interval_seconds".into(), json!(config.tick_interval_seconds));
    body.insert("base_backoff_seconds".into(), json!(config.base_backoff_seconds));
    body.insert("max_backoff_seconds".into(), json!(config.max_backoff_seconds));
    // Only forward the token when the operator actually typed one.
    // Sending an empty string would clear it.
    if !config.client_token.is_empty() {
        body.insert("client_token".into(), json!(config.client_token));
    }
    make_request(&state, Operation::Write, format!("{mount}/scheduler/config"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn cert_lifecycle_list_deliverers(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<Vec<String>> {
    let mount = mount_prefix(&mount);
    let resp =
        make_request(&state, Operation::Read, format!("{mount}/sys/deliverers"), None).await?;
    Ok(val_str_array(&data_to_map(resp), "deliverers"))
}

// Avoid unused-import lints if a future refactor drops a helper.
#[allow(dead_code)]
fn _unused_imports() {
    let _: HashMap<(), ()> = HashMap::new();
}
