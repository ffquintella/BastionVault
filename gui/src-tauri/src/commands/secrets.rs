use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

#[derive(Serialize)]
pub struct SecretData {
    pub data: HashMap<String, Value>,
}

#[derive(Serialize)]
pub struct SecretListResult {
    pub keys: Vec<String>,
}

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

    core.handle_request(&mut req)
        .await
        .map_err(CommandError::from)
}

/// Adjust a KV path for v2 by inserting the appropriate prefix after the mount.
fn adjust_kv_path(path: &str, mount: &str, mount_type: &str, prefix: &str) -> String {
    if mount_type == "kv-v2" && !mount.is_empty() {
        let rel = path.strip_prefix(mount).unwrap_or(path);
        format!("{mount}{prefix}/{rel}")
    } else {
        path.to_string()
    }
}

#[tauri::command]
pub async fn list_secrets(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<SecretListResult> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let actual_path = adjust_kv_path(&path, m, mt, "metadata");
    let resp = make_request(&state, Operation::List, actual_path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let keys: Vec<String> = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(SecretListResult { keys });
                }
            }
            Ok(SecretListResult { keys: vec![] })
        }
        None => Ok(SecretListResult { keys: vec![] }),
    }
}

#[tauri::command]
pub async fn read_secret(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<SecretData> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let actual_path = adjust_kv_path(&path, m, mt, "data");
    let resp = make_request(&state, Operation::Read, actual_path, None).await?;

    match resp {
        Some(r) => {
            let raw = r.data.unwrap_or_default();
            // v2 nests the actual secret under a "data" key
            let data = if mt == "kv-v2" {
                raw.get("data")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or(raw)
                    .into_iter()
                    .collect()
            } else {
                raw.into_iter().collect()
            };
            Ok(SecretData { data })
        }
        None => Err("Secret not found".into()),
    }
}

#[tauri::command]
pub async fn write_secret(
    state: State<'_, AppState>,
    path: String,
    data: HashMap<String, String>,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let actual_path = adjust_kv_path(&path, m, mt, "data");

    let mut kv_body = Map::new();
    for (k, v) in data {
        kv_body.insert(k, Value::String(v));
    }

    // v2 wraps the data in a "data" envelope
    let body = if mt == "kv-v2" {
        let mut wrapper = Map::new();
        wrapper.insert("data".to_string(), Value::Object(kv_body));
        wrapper
    } else {
        kv_body
    };

    make_request(&state, Operation::Write, actual_path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_secret(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<()> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    let actual_path = adjust_kv_path(&path, m, mt, "metadata");
    make_request(&state, Operation::Delete, actual_path, None).await?;
    Ok(())
}

// ── Secret history / versions ──────────────────────────────────────

#[derive(Serialize)]
pub struct SecretVersionInfo {
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    pub username: String,
    pub operation: String,
}

#[derive(Serialize)]
pub struct SecretVersionListResult {
    pub current_version: u64,
    pub oldest_version: u64,
    pub versions: Vec<SecretVersionInfo>,
}

#[derive(Serialize)]
pub struct SecretVersionData {
    pub data: HashMap<String, Value>,
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
    pub username: String,
    pub operation: String,
}

/// List every stored version of a KV-v2 secret (newest first). Returns
/// the per-version metadata -- `created_time`, the username of whoever
/// wrote it, and the soft-delete/destroy state. KV-v1 does not support
/// versioning; callers receive an empty list in that case.
#[tauri::command]
pub async fn list_secret_versions(
    state: State<'_, AppState>,
    path: String,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<SecretVersionListResult> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Ok(SecretVersionListResult {
            current_version: 0,
            oldest_version: 0,
            versions: vec![],
        });
    }
    let actual_path = adjust_kv_path(&path, m, mt, "metadata");
    let resp = make_request(&state, Operation::Read, actual_path, None).await?;

    let data = match resp.and_then(|r| r.data) {
        Some(d) => d,
        None => {
            return Ok(SecretVersionListResult {
                current_version: 0,
                oldest_version: 0,
                versions: vec![],
            });
        }
    };

    let current_version = data
        .get("current_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let oldest_version = data
        .get("oldest_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mut versions: Vec<SecretVersionInfo> = Vec::new();
    if let Some(Value::Object(vmap)) = data.get("versions") {
        for (k, v) in vmap {
            let Ok(version) = k.parse::<u64>() else { continue };
            let obj = match v.as_object() {
                Some(o) => o,
                None => continue,
            };
            versions.push(SecretVersionInfo {
                version,
                created_time: obj
                    .get("created_time")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                deletion_time: obj
                    .get("deletion_time")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                destroyed: obj
                    .get("destroyed")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                username: obj
                    .get("username")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                operation: obj
                    .get("operation")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    // Newest version first.
    versions.sort_by(|a, b| b.version.cmp(&a.version));

    Ok(SecretVersionListResult {
        current_version,
        oldest_version,
        versions,
    })
}

/// Read a specific historical version of a KV-v2 secret. Not valid for
/// KV-v1 (where only the current value exists).
#[tauri::command]
pub async fn read_secret_version(
    state: State<'_, AppState>,
    path: String,
    version: u64,
    mount: Option<String>,
    mount_type: Option<String>,
) -> CmdResult<SecretVersionData> {
    let m = mount.as_deref().unwrap_or("");
    let mt = mount_type.as_deref().unwrap_or("kv");
    if mt != "kv-v2" {
        return Err("Versioning is only available on kv-v2 mounts".into());
    }
    let actual_path = adjust_kv_path(&path, m, mt, "data");

    let mut body = Map::new();
    body.insert("version".to_string(), Value::from(version));
    let resp = make_request(&state, Operation::Read, actual_path, Some(body)).await?;

    let raw = resp.and_then(|r| r.data).ok_or("Version not found")?;
    let data_map = raw
        .get("data")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let meta = raw
        .get("metadata")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    Ok(SecretVersionData {
        data: data_map.into_iter().collect(),
        version: meta.get("version").and_then(|v| v.as_u64()).unwrap_or(version),
        created_time: meta
            .get("created_time")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        deletion_time: meta
            .get("deletion_time")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        destroyed: meta
            .get("destroyed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        username: meta
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        operation: meta
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[tauri::command]
pub async fn mount_engine(
    state: State<'_, AppState>,
    path: String,
    engine_type: String,
    description: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("type".to_string(), Value::String(engine_type));
    if !description.is_empty() {
        body.insert("description".to_string(), Value::String(description));
    }

    make_request(
        &state,
        Operation::Write,
        format!("sys/mounts/{path}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn unmount_engine(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("sys/mounts/{path}"), None).await?;
    Ok(())
}

#[tauri::command]
pub async fn enable_auth_method(
    state: State<'_, AppState>,
    path: String,
    auth_type: String,
    description: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("type".to_string(), Value::String(auth_type));
    if !description.is_empty() {
        body.insert("description".to_string(), Value::String(description));
    }

    make_request(
        &state,
        Operation::Write,
        format!("sys/auth/{path}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn disable_auth_method(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("sys/auth/{path}"), None).await?;
    Ok(())
}
