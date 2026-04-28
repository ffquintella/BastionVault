//! Tauri commands bridging the desktop GUI to the OpenLDAP / AD
//! password-rotation engine.
//!
//! Same `make_request` thin-wrapper pattern as [`super::ssh`] /
//! [`super::pki`] / [`super::transit`] — each command builds a
//! synthetic `Request` and routes it through the open vault's
//! core. Mount path is parameterised so an operator who mounted at
//! `openldap-prod/` rather than `openldap/` can drive both from
//! the same UI.

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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
        "openldap".to_string()
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

fn val_bool(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

// ── Mount lifecycle ──────────────────────────────────────────────

#[derive(Serialize)]
pub struct LdapMountInfo {
    pub path: String,
}

#[tauri::command]
pub async fn ldap_list_mounts(state: State<'_, AppState>) -> CmdResult<Vec<LdapMountInfo>> {
    let resp = make_request(&state, Operation::Read, "sys/mounts".into(), None).await?;
    let map = data_to_map(resp);
    let mut out = Vec::new();
    for (path, info) in map.iter() {
        if let Some(t) = info.get("type").and_then(|v| v.as_str()) {
            if t == "openldap" {
                out.push(LdapMountInfo { path: path.clone() });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[tauri::command]
pub async fn ldap_enable_mount(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let mount_path = path.trim().trim_end_matches('/').to_string();
    if mount_path.is_empty() {
        return Err("mount path required".into());
    }
    let mut body = Map::new();
    body.insert("type".into(), Value::String("openldap".into()));
    let api_path = format!("sys/mounts/{mount_path}/");
    make_request(&state, Operation::Write, api_path, Some(body)).await?;
    Ok(())
}

// ── Connection config ────────────────────────────────────────────

#[derive(Serialize, Default)]
pub struct LdapConfigInfo {
    pub url: String,
    pub binddn: String,
    pub userdn: String,
    pub directory_type: String,
    pub password_policy: String,
    pub request_timeout: u64,
    pub starttls: bool,
    pub tls_min_version: String,
    pub insecure_tls: bool,
    pub userattr: String,
    /// Always empty on read — bindpass is redacted server-side. The
    /// type stays in the shape so the GUI form can preserve a
    /// rendered value across edits.
    pub bindpass: String,
}

#[tauri::command]
pub async fn ldap_read_config(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<Option<LdapConfigInfo>> {
    let path = format!("{}/config", mount_prefix(&mount));
    let resp = make_request(&state, Operation::Read, path, None).await?;
    if resp.is_none() {
        return Ok(None);
    }
    let map = data_to_map(resp);
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(LdapConfigInfo {
        url: val_str(&map, "url"),
        binddn: val_str(&map, "binddn"),
        userdn: val_str(&map, "userdn"),
        directory_type: val_str(&map, "directory_type"),
        password_policy: val_str(&map, "password_policy"),
        request_timeout: val_u64(&map, "request_timeout"),
        starttls: val_bool(&map, "starttls"),
        tls_min_version: val_str(&map, "tls_min_version"),
        insecure_tls: val_bool(&map, "insecure_tls"),
        userattr: val_str(&map, "userattr"),
        bindpass: String::new(),
    }))
}

#[derive(Deserialize)]
pub struct LdapWriteConfigRequest {
    pub mount: String,
    pub url: String,
    pub binddn: String,
    /// Empty preserves the previous value (the engine's partial-update
    /// semantic). Set to a non-empty string to rotate.
    pub bindpass: Option<String>,
    pub userdn: Option<String>,
    pub directory_type: Option<String>,
    pub password_policy: Option<String>,
    pub request_timeout: Option<u64>,
    pub starttls: Option<bool>,
    pub tls_min_version: Option<String>,
    pub insecure_tls: Option<bool>,
    pub acknowledge_insecure_tls: Option<bool>,
    pub userattr: Option<String>,
}

#[tauri::command]
pub async fn ldap_write_config(
    state: State<'_, AppState>,
    request: LdapWriteConfigRequest,
) -> CmdResult<()> {
    let path = format!("{}/config", mount_prefix(&request.mount));
    let mut body = Map::new();
    body.insert("url".into(), Value::String(request.url));
    body.insert("binddn".into(), Value::String(request.binddn));
    if let Some(p) = request.bindpass.filter(|s| !s.is_empty()) {
        body.insert("bindpass".into(), Value::String(p));
    }
    if let Some(s) = request.userdn {
        body.insert("userdn".into(), Value::String(s));
    }
    if let Some(s) = request.directory_type {
        body.insert("directory_type".into(), Value::String(s));
    }
    if let Some(s) = request.password_policy {
        body.insert("password_policy".into(), Value::String(s));
    }
    if let Some(n) = request.request_timeout {
        body.insert("request_timeout".into(), Value::Number(n.into()));
    }
    if let Some(b) = request.starttls {
        body.insert("starttls".into(), Value::Bool(b));
    }
    if let Some(s) = request.tls_min_version {
        body.insert("tls_min_version".into(), Value::String(s));
    }
    if let Some(b) = request.insecure_tls {
        body.insert("insecure_tls".into(), Value::Bool(b));
    }
    if let Some(b) = request.acknowledge_insecure_tls {
        body.insert("acknowledge_insecure_tls".into(), Value::Bool(b));
    }
    if let Some(s) = request.userattr {
        body.insert("userattr".into(), Value::String(s));
    }
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ldap_delete_config(state: State<'_, AppState>, mount: String) -> CmdResult<()> {
    let path = format!("{}/config", mount_prefix(&mount));
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

#[tauri::command]
pub async fn ldap_rotate_root(state: State<'_, AppState>, mount: String) -> CmdResult<()> {
    let path = format!("{}/rotate-root", mount_prefix(&mount));
    make_request(&state, Operation::Write, path, None).await?;
    Ok(())
}

// ── Static roles ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct LdapStaticRole {
    pub dn: String,
    pub username: String,
    pub rotation_period: u64,
    pub password_policy: String,
}

#[tauri::command]
pub async fn ldap_list_static_roles(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<Vec<String>> {
    let path = format!("{}/static-role", mount_prefix(&mount));
    let resp = make_request(&state, Operation::List, path, None).await?;
    let map = data_to_map(resp);
    Ok(map
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default())
}

#[tauri::command]
pub async fn ldap_read_static_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<Option<LdapStaticRole>> {
    let path = format!("{}/static-role/{}", mount_prefix(&mount), name);
    let resp = make_request(&state, Operation::Read, path, None).await?;
    if resp.is_none() {
        return Ok(None);
    }
    let map = data_to_map(resp);
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(LdapStaticRole {
        dn: val_str(&map, "dn"),
        username: val_str(&map, "username"),
        rotation_period: val_u64(&map, "rotation_period"),
        password_policy: val_str(&map, "password_policy"),
    }))
}

#[tauri::command]
pub async fn ldap_write_static_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
    role: LdapStaticRole,
) -> CmdResult<()> {
    let path = format!("{}/static-role/{}", mount_prefix(&mount), name);
    let mut body = Map::new();
    body.insert("dn".into(), Value::String(role.dn));
    body.insert("username".into(), Value::String(role.username));
    body.insert(
        "rotation_period".into(),
        Value::Number(role.rotation_period.into()),
    );
    if !role.password_policy.is_empty() {
        body.insert("password_policy".into(), Value::String(role.password_policy));
    }
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ldap_delete_static_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    let path = format!("{}/static-role/{}", mount_prefix(&mount), name);
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

#[derive(Serialize, Default)]
pub struct LdapStaticCred {
    pub username: String,
    pub dn: String,
    pub password: String,
    pub last_vault_rotation_unix: u64,
    /// Seconds until the next auto-rotation. `None` when the role's
    /// `rotation_period == 0` (manual rotation only).
    pub ttl_secs: Option<u64>,
}

#[tauri::command]
pub async fn ldap_read_static_cred(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<LdapStaticCred> {
    let path = format!("{}/static-cred/{}", mount_prefix(&mount), name);
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let map = data_to_map(resp);
    let ttl_secs = map.get("ttl_secs").and_then(|v| v.as_u64());
    Ok(LdapStaticCred {
        username: val_str(&map, "username"),
        dn: val_str(&map, "dn"),
        password: val_str(&map, "password"),
        last_vault_rotation_unix: val_u64(&map, "last_vault_rotation_unix"),
        ttl_secs,
    })
}

#[derive(Serialize, Default)]
pub struct LdapRotateRoleResult {
    pub username: String,
    pub dn: String,
    pub password: String,
    pub last_vault_rotation_unix: u64,
}

#[tauri::command]
pub async fn ldap_rotate_role(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<LdapRotateRoleResult> {
    let path = format!("{}/rotate-role/{}", mount_prefix(&mount), name);
    let resp = make_request(&state, Operation::Write, path, None).await?;
    let map = data_to_map(resp);
    Ok(LdapRotateRoleResult {
        username: val_str(&map, "username"),
        dn: val_str(&map, "dn"),
        password: val_str(&map, "password"),
        last_vault_rotation_unix: val_u64(&map, "last_vault_rotation_unix"),
    })
}

// ── Library / check-out / check-in ───────────────────────────────

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct LdapLibrarySet {
    pub service_account_names: Vec<String>,
    pub ttl: u64,
    pub max_ttl: u64,
    pub disable_check_in_enforcement: bool,
}

#[tauri::command]
pub async fn ldap_list_libraries(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<Vec<String>> {
    let path = format!("{}/library", mount_prefix(&mount));
    let resp = make_request(&state, Operation::List, path, None).await?;
    let map = data_to_map(resp);
    Ok(map
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default())
}

#[tauri::command]
pub async fn ldap_read_library(
    state: State<'_, AppState>,
    mount: String,
    set: String,
) -> CmdResult<Option<LdapLibrarySet>> {
    let path = format!("{}/library/{}", mount_prefix(&mount), set);
    let resp = make_request(&state, Operation::Read, path, None).await?;
    if resp.is_none() {
        return Ok(None);
    }
    let map = data_to_map(resp);
    if map.is_empty() {
        return Ok(None);
    }
    let names: Vec<String> = map
        .get("service_account_names")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    Ok(Some(LdapLibrarySet {
        service_account_names: names,
        ttl: val_u64(&map, "ttl"),
        max_ttl: val_u64(&map, "max_ttl"),
        disable_check_in_enforcement: val_bool(&map, "disable_check_in_enforcement"),
    }))
}

#[tauri::command]
pub async fn ldap_write_library(
    state: State<'_, AppState>,
    mount: String,
    set: String,
    config: LdapLibrarySet,
) -> CmdResult<()> {
    let path = format!("{}/library/{}", mount_prefix(&mount), set);
    let mut body = Map::new();
    body.insert(
        "service_account_names".into(),
        Value::String(config.service_account_names.join(",")),
    );
    body.insert("ttl".into(), Value::Number(config.ttl.into()));
    body.insert("max_ttl".into(), Value::Number(config.max_ttl.into()));
    body.insert(
        "disable_check_in_enforcement".into(),
        Value::Bool(config.disable_check_in_enforcement),
    );
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn ldap_delete_library(
    state: State<'_, AppState>,
    mount: String,
    set: String,
) -> CmdResult<()> {
    let path = format!("{}/library/{}", mount_prefix(&mount), set);
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

#[derive(Serialize, Default)]
pub struct LdapCheckOutResult {
    pub service_account_name: String,
    pub password: String,
    pub lease_id: String,
    pub ttl_secs: u64,
}

#[tauri::command]
pub async fn ldap_check_out(
    state: State<'_, AppState>,
    mount: String,
    set: String,
    ttl: Option<u64>,
) -> CmdResult<LdapCheckOutResult> {
    let path = format!("{}/library/{}/check-out", mount_prefix(&mount), set);
    let mut body = Map::new();
    if let Some(t) = ttl.filter(|n| *n > 0) {
        body.insert("ttl".into(), Value::Number(t.into()));
    }
    let resp = make_request(&state, Operation::Write, path, Some(body)).await?;
    let map = data_to_map(resp);
    Ok(LdapCheckOutResult {
        service_account_name: val_str(&map, "service_account_name"),
        password: val_str(&map, "password"),
        lease_id: val_str(&map, "lease_id"),
        ttl_secs: val_u64(&map, "ttl_secs"),
    })
}

#[tauri::command]
pub async fn ldap_check_in(
    state: State<'_, AppState>,
    mount: String,
    set: String,
    account: Option<String>,
) -> CmdResult<()> {
    let path = format!("{}/library/{}/check-in", mount_prefix(&mount), set);
    let mut body = Map::new();
    if let Some(a) = account.filter(|s| !s.is_empty()) {
        body.insert("account".into(), Value::String(a));
    }
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[derive(Serialize, Default)]
pub struct LdapLibraryStatus {
    /// Account name → metadata. Keeps the shape stable for the GUI's
    /// per-account row renderer.
    pub checked_out: Vec<LdapLibraryStatusEntry>,
    pub available: Vec<String>,
}

#[derive(Serialize, Default)]
pub struct LdapLibraryStatusEntry {
    pub account: String,
    pub lease_id: String,
    pub expires_at_unix: u64,
}

#[tauri::command]
pub async fn ldap_library_status(
    state: State<'_, AppState>,
    mount: String,
    set: String,
) -> CmdResult<LdapLibraryStatus> {
    let path = format!("{}/library/{}/status", mount_prefix(&mount), set);
    let resp = make_request(&state, Operation::Read, path, None).await?;
    let map = data_to_map(resp);
    let mut checked_out = Vec::new();
    if let Some(obj) = map.get("checked_out").and_then(|v| v.as_object()) {
        for (account, entry) in obj {
            let inner = entry.as_object().cloned().unwrap_or_default();
            checked_out.push(LdapLibraryStatusEntry {
                account: account.clone(),
                lease_id: val_str(&inner, "lease_id"),
                expires_at_unix: val_u64(&inner, "expires_at_unix"),
            });
        }
    }
    let available: Vec<String> = map
        .get("available")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    Ok(LdapLibraryStatus {
        checked_out,
        available,
    })
}
