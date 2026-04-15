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

#[tauri::command]
pub async fn list_secrets(state: State<'_, AppState>, path: String) -> CmdResult<SecretListResult> {
    let resp = make_request(&state, Operation::List, path, None).await?;

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
pub async fn read_secret(state: State<'_, AppState>, path: String) -> CmdResult<SecretData> {
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            let data = r
                .data
                .map(|m| m.into_iter().collect::<HashMap<String, Value>>())
                .unwrap_or_default();
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
) -> CmdResult<()> {
    let mut body = Map::new();
    for (k, v) in data {
        body.insert(k, Value::String(v));
    }

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_secret(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, path, None).await?;
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
