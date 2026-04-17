use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

/// The dedicated resource engine is mounted at this path.
const RESOURCE_MOUNT: &str = "resources/";

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

// ── Resource Metadata ──────────────────────────────────────────────

/// ResourceMetadata is now a flexible JSON object — the frontend defines the schema
/// based on the resource type configuration. We just pass it through.
type ResourceMetadata = Map<String, Value>;

#[derive(Serialize)]
pub struct ResourceListResult {
    pub resources: Vec<String>,
}

#[derive(Serialize)]
pub struct ResourceSecretListResult {
    pub keys: Vec<String>,
}

#[derive(Serialize)]
pub struct ResourceSecretData {
    pub data: HashMap<String, Value>,
}

// ── Type Configuration ─────────────────────────────────────────────

#[tauri::command]
pub async fn resource_types_read(state: State<'_, AppState>) -> CmdResult<Option<Value>> {
    let path = format!("{RESOURCE_MOUNT}config/types");
    let resp = make_request(&state, Operation::Read, path, None).await?;
    match resp {
        Some(r) => Ok(r.data.map(Value::Object)),
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn resource_types_write(state: State<'_, AppState>, types: Value) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}config/types");
    let body = types.as_object().cloned()
        .ok_or_else(|| CommandError::from("types must be a JSON object"))?;
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

// ── Resource CRUD ──────────────────────────────────────────────────
// Uses the dedicated resource engine at resources/

#[tauri::command]
pub async fn list_resources(
    state: State<'_, AppState>,
    // mount and mount_type kept for API compat but ignored — we always use RESOURCE_MOUNT
    #[allow(unused_variables)] mount: Option<String>,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceListResult> {
    let path = format!("{RESOURCE_MOUNT}resources/");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let resources = keys.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(ResourceListResult { resources });
                }
            }
            Ok(ResourceListResult { resources: vec![] })
        }
        None => Ok(ResourceListResult { resources: vec![] }),
    }
}

#[tauri::command]
pub async fn read_resource(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceMetadata> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = r.data {
                return Ok(data);
            }
            Err("Resource not found".into())
        }
        None => Err("Resource not found".into()),
    }
}

#[tauri::command]
pub async fn write_resource(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    metadata: ResourceMetadata,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}");

    let mut body = metadata;
    body.insert("name".to_string(), Value::String(name));
    let now = chrono::Utc::now().to_rfc3339();
    if !body.contains_key("created_at") || body.get("created_at").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
        body.insert("created_at".to_string(), Value::String(now.clone()));
    }
    body.insert("updated_at".to_string(), Value::String(now));

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_resource(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}resources/{name}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}

// ── Resource Secrets ───────────────────────────────────────────────

#[tauri::command]
pub async fn list_resource_secrets(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceSecretListResult> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let keys = keys.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(ResourceSecretListResult { keys });
                }
            }
            Ok(ResourceSecretListResult { keys: vec![] })
        }
        None => Ok(ResourceSecretListResult { keys: vec![] }),
    }
}

#[tauri::command]
pub async fn read_resource_secret(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    key: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<ResourceSecretData> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            let data = r.data
                .map(|m| m.into_iter().collect::<HashMap<String, Value>>())
                .unwrap_or_default();
            Ok(ResourceSecretData { data })
        }
        None => Err("Secret not found".into()),
    }
}

#[tauri::command]
pub async fn write_resource_secret(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    key: String,
    data: HashMap<String, String>,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}");
    let mut body = Map::new();
    for (k, v) in data {
        body.insert(k, Value::String(v));
    }
    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_resource_secret(
    state: State<'_, AppState>,
    #[allow(unused_variables)] mount: Option<String>,
    name: String,
    key: String,
    #[allow(unused_variables)] mount_type: Option<String>,
) -> CmdResult<()> {
    let path = format!("{RESOURCE_MOUNT}secrets/{name}/{key}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}
