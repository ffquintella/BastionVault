use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::{CmdResult, CommandError};
use crate::state::AppState;

const RESOURCES_PREFIX: &str = "_resources/";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetadata {
    #[serde(default = "default_true")]
    pub _resource: bool,
    pub name: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub ip_address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

fn default_true() -> bool {
    true
}

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

// ── Resource CRUD ──────────────────────────────────────────────────

#[tauri::command]
pub async fn list_resources(
    state: State<'_, AppState>,
    mount: String,
) -> CmdResult<ResourceListResult> {
    let path = format!("{mount}{RESOURCES_PREFIX}");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let resources = keys
                        .iter()
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
    mount: String,
    name: String,
) -> CmdResult<ResourceMetadata> {
    let path = format!("{mount}{RESOURCES_PREFIX}{name}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = r.data {
                let value = Value::Object(data);
                let meta: ResourceMetadata =
                    serde_json::from_value(value).map_err(|e| CommandError::from(e.to_string()))?;
                return Ok(meta);
            }
            Err("Resource not found".into())
        }
        None => Err("Resource not found".into()),
    }
}

#[tauri::command]
pub async fn write_resource(
    state: State<'_, AppState>,
    mount: String,
    name: String,
    metadata: ResourceMetadata,
) -> CmdResult<()> {
    let path = format!("{mount}{RESOURCES_PREFIX}{name}");

    let mut meta = metadata;
    meta._resource = true;
    meta.name = name;
    let now = chrono::Utc::now().to_rfc3339();
    if meta.created_at.is_empty() {
        meta.created_at = now.clone();
    }
    meta.updated_at = now;

    let value = serde_json::to_value(&meta).map_err(|e| CommandError::from(e.to_string()))?;
    let body = value
        .as_object()
        .cloned()
        .ok_or_else(|| CommandError::from("Failed to serialize metadata"))?;

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_resource(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<()> {
    // Delete the resource metadata.
    let meta_path = format!("{mount}{RESOURCES_PREFIX}{name}");
    make_request(&state, Operation::Delete, meta_path, None).await?;

    // Delete all secrets under the resource path.
    let secrets_path = format!("{mount}{name}/");
    let resp = make_request(&state, Operation::List, secrets_path.clone(), None).await;
    if let Ok(Some(r)) = resp {
        if let Some(data) = &r.data {
            if let Some(Value::Array(keys)) = data.get("keys") {
                for key in keys {
                    if let Some(k) = key.as_str() {
                        let _ = make_request(
                            &state,
                            Operation::Delete,
                            format!("{mount}{name}/{k}"),
                            None,
                        )
                        .await;
                    }
                }
            }
        }
    }

    Ok(())
}

// ── Resource Secrets ───────────────────────────────────────────────

#[tauri::command]
pub async fn list_resource_secrets(
    state: State<'_, AppState>,
    mount: String,
    name: String,
) -> CmdResult<ResourceSecretListResult> {
    let path = format!("{mount}{name}/");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let keys = keys
                        .iter()
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
    mount: String,
    name: String,
    key: String,
) -> CmdResult<ResourceSecretData> {
    let path = format!("{mount}{name}/{key}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            let data = r
                .data
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
    mount: String,
    name: String,
    key: String,
    data: HashMap<String, String>,
) -> CmdResult<()> {
    let path = format!("{mount}{name}/{key}");
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
    mount: String,
    name: String,
    key: String,
) -> CmdResult<()> {
    let path = format!("{mount}{name}/{key}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}
