use std::collections::HashMap;

use bastion_vault::logical::{Operation, Request};
use serde::Serialize;
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

    core.handle_request(&mut req)
        .await
        .map_err(CommandError::from)
}

// ── Role CRUD ──────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AppRoleListResult {
    pub roles: Vec<String>,
}

#[derive(Serialize)]
pub struct AppRoleInfo {
    pub name: String,
    pub bind_secret_id: bool,
    pub secret_id_num_uses: i64,
    pub secret_id_ttl: u64,
    pub token_policies: Vec<String>,
    pub token_ttl: u64,
    pub token_max_ttl: u64,
    pub token_num_uses: i64,
    pub secret_id_bound_cidrs: Vec<String>,
    pub token_bound_cidrs: Vec<String>,
}

#[tauri::command]
pub async fn list_approles(state: State<'_, AppState>) -> CmdResult<AppRoleListResult> {
    let resp = make_request(&state, Operation::List, "auth/approle/role/".into(), None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let roles = keys.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    return Ok(AppRoleListResult { roles });
                }
            }
            Ok(AppRoleListResult { roles: vec![] })
        }
        None => Ok(AppRoleListResult { roles: vec![] }),
    }
}

#[tauri::command]
pub async fn read_approle(state: State<'_, AppState>, name: String) -> CmdResult<AppRoleInfo> {
    let resp = make_request(&state, Operation::Read, format!("auth/approle/role/{name}"), None).await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            let get_str_vec = |key: &str| -> Vec<String> {
                data.and_then(|d| d.get(key))
                    .and_then(|v| match v {
                        Value::Array(a) => Some(a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
                        Value::String(s) => Some(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
                        _ => None,
                    })
                    .unwrap_or_default()
            };

            Ok(AppRoleInfo {
                name,
                bind_secret_id: data.and_then(|d| d.get("bind_secret_id")).and_then(|v| v.as_bool()).unwrap_or(true),
                secret_id_num_uses: data.and_then(|d| d.get("secret_id_num_uses")).and_then(|v| v.as_i64()).unwrap_or(0),
                secret_id_ttl: data.and_then(|d| d.get("secret_id_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                token_policies: get_str_vec("token_policies"),
                token_ttl: data.and_then(|d| d.get("token_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                token_max_ttl: data.and_then(|d| d.get("token_max_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                token_num_uses: data.and_then(|d| d.get("token_num_uses")).and_then(|v| v.as_i64()).unwrap_or(0),
                secret_id_bound_cidrs: get_str_vec("secret_id_bound_cidrs"),
                token_bound_cidrs: get_str_vec("token_bound_cidrs"),
            })
        }
        None => Err("Role not found".into()),
    }
}

#[tauri::command]
pub async fn write_approle(
    state: State<'_, AppState>,
    name: String,
    bind_secret_id: bool,
    token_policies: String,
    secret_id_num_uses: i64,
    secret_id_ttl: String,
    token_ttl: String,
    token_max_ttl: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("bind_secret_id".into(), Value::Bool(bind_secret_id));
    if !token_policies.is_empty() {
        body.insert("token_policies".into(), Value::String(token_policies));
    }
    body.insert("secret_id_num_uses".into(), Value::Number(secret_id_num_uses.into()));
    if !secret_id_ttl.is_empty() {
        body.insert("secret_id_ttl".into(), Value::String(secret_id_ttl));
    }
    if !token_ttl.is_empty() {
        body.insert("token_ttl".into(), Value::String(token_ttl));
    }
    if !token_max_ttl.is_empty() {
        body.insert("token_max_ttl".into(), Value::String(token_max_ttl));
    }

    make_request(&state, Operation::Write, format!("auth/approle/role/{name}"), Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_approle(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(&state, Operation::Delete, format!("auth/approle/role/{name}"), None).await?;
    Ok(())
}

// ── Role ID ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RoleIdInfo {
    pub role_id: String,
}

#[tauri::command]
pub async fn read_role_id(state: State<'_, AppState>, name: String) -> CmdResult<RoleIdInfo> {
    let resp = make_request(&state, Operation::Read, format!("auth/approle/role/{name}/role-id"), None).await?;

    match resp {
        Some(r) => {
            let role_id = r.data.as_ref()
                .and_then(|d| d.get("role_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(RoleIdInfo { role_id })
        }
        None => Err("Role ID not found".into()),
    }
}

// ── Secret ID Management ───────────────────────────────────────────

#[derive(Serialize)]
pub struct SecretIdResponse {
    pub secret_id: String,
    pub secret_id_accessor: String,
    pub secret_id_ttl: u64,
}

#[derive(Serialize)]
pub struct SecretIdAccessorList {
    pub accessors: Vec<String>,
}

#[derive(Serialize)]
pub struct SecretIdAccessorInfo {
    pub secret_id_accessor: String,
    pub secret_id_num_uses: i64,
    pub secret_id_ttl: u64,
    pub creation_time: String,
    pub expiration_time: String,
    pub metadata: HashMap<String, String>,
    pub cidr_list: Vec<String>,
}

#[tauri::command]
pub async fn generate_secret_id(
    state: State<'_, AppState>,
    name: String,
    metadata: String,
) -> CmdResult<SecretIdResponse> {
    let mut body = Map::new();
    if !metadata.is_empty() {
        body.insert("metadata".into(), Value::String(metadata));
    }

    let resp = make_request(
        &state,
        Operation::Write,
        format!("auth/approle/role/{name}/secret-id/"),
        Some(body),
    ).await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            Ok(SecretIdResponse {
                secret_id: data.and_then(|d| d.get("secret_id")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                secret_id_accessor: data.and_then(|d| d.get("secret_id_accessor")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                secret_id_ttl: data.and_then(|d| d.get("secret_id_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
            })
        }
        None => Err("Failed to generate secret ID".into()),
    }
}

#[tauri::command]
pub async fn list_secret_id_accessors(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<SecretIdAccessorList> {
    let resp = make_request(
        &state,
        Operation::List,
        format!("auth/approle/role/{name}/secret-id/"),
        None,
    ).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let accessors = keys.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    return Ok(SecretIdAccessorList { accessors });
                }
            }
            Ok(SecretIdAccessorList { accessors: vec![] })
        }
        None => Ok(SecretIdAccessorList { accessors: vec![] }),
    }
}

#[tauri::command]
pub async fn lookup_secret_id_accessor(
    state: State<'_, AppState>,
    name: String,
    accessor: String,
) -> CmdResult<SecretIdAccessorInfo> {
    let mut body = Map::new();
    body.insert("secret_id_accessor".into(), Value::String(accessor.clone()));

    let resp = make_request(
        &state,
        Operation::Write,
        format!("auth/approle/role/{name}/secret-id-accessor/lookup/"),
        Some(body),
    ).await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();

            let metadata: HashMap<String, String> = data
                .and_then(|d| d.get("metadata"))
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let cidr_list: Vec<String> = data
                .and_then(|d| d.get("cidr_list"))
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();

            Ok(SecretIdAccessorInfo {
                secret_id_accessor: accessor,
                secret_id_num_uses: data.and_then(|d| d.get("secret_id_num_uses")).and_then(|v| v.as_i64()).unwrap_or(0),
                secret_id_ttl: data.and_then(|d| d.get("secret_id_ttl")).and_then(|v| v.as_u64()).unwrap_or(0),
                creation_time: data.and_then(|d| d.get("creation_time")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                expiration_time: data.and_then(|d| d.get("expiration_time")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                metadata,
                cidr_list,
            })
        }
        None => Err("Accessor not found".into()),
    }
}

#[tauri::command]
pub async fn destroy_secret_id_accessor(
    state: State<'_, AppState>,
    name: String,
    accessor: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("secret_id_accessor".into(), Value::String(accessor));

    make_request(
        &state,
        Operation::Write,
        format!("auth/approle/role/{name}/secret-id-accessor/destroy/"),
        Some(body),
    ).await?;
    Ok(())
}
