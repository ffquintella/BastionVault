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
