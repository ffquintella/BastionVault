//! Tauri commands for the asset-group backend (internally named
//! `resource-group` for backward compatibility). Mirrors the shape of
//! the identity-group commands so the GUI can reuse the same
//! interaction pattern; the payload differs because asset groups carry
//! `members` (resource names) *and* `secrets` (KV paths) but no
//! policies of their own.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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

#[derive(Serialize)]
pub struct AssetGroupListResult {
    pub groups: Vec<String>,
}

#[derive(Serialize)]
pub struct AssetGroupInfo {
    pub name: String,
    pub description: String,
    pub members: Vec<String>,
    pub secrets: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct AssetGroupHistoryEntry {
    pub ts: String,
    pub user: String,
    pub op: String,
    pub changed_fields: Vec<String>,
    /// Field values before the change. Empty for `create`. Keys are a
    /// subset of {description, members, secrets}; `description` is a
    /// string, `members` and `secrets` are arrays of strings.
    pub before: Map<String, Value>,
    /// Field values after the change. Empty for `delete`.
    pub after: Map<String, Value>,
}

#[derive(Serialize)]
pub struct AssetGroupHistoryResult {
    pub entries: Vec<AssetGroupHistoryEntry>,
}

#[derive(Serialize)]
pub struct AssetGroupLookupResult {
    pub groups: Vec<String>,
}

fn data_string_list(data: Option<&Map<String, Value>>, key: &str) -> Vec<String> {
    data.and_then(|d| d.get(key))
        .and_then(|v| match v {
            Value::Array(a) => Some(
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect(),
            ),
            Value::String(s) => Some(
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

#[tauri::command]
pub async fn list_asset_groups(state: State<'_, AppState>) -> CmdResult<AssetGroupListResult> {
    let resp = make_request(&state, Operation::List, "resource-group/groups/".into(), None).await?;
    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let groups = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(AssetGroupListResult { groups });
                }
            }
            Ok(AssetGroupListResult { groups: vec![] })
        }
        None => Ok(AssetGroupListResult { groups: vec![] }),
    }
}

#[tauri::command]
pub async fn read_asset_group(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<AssetGroupInfo> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("resource-group/groups/{name}"),
        None,
    )
    .await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            Ok(AssetGroupInfo {
                name: data
                    .and_then(|d| d.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&name)
                    .to_string(),
                description: data
                    .and_then(|d| d.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                members: data_string_list(data, "members"),
                secrets: data_string_list(data, "secrets"),
                created_at: data
                    .and_then(|d| d.get("created_at"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                updated_at: data
                    .and_then(|d| d.get("updated_at"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            })
        }
        None => Err("Asset group not found".into()),
    }
}

#[tauri::command]
pub async fn write_asset_group(
    state: State<'_, AppState>,
    name: String,
    description: String,
    members: String,
    secrets: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("description".into(), Value::String(description));
    body.insert("members".into(), Value::String(members));
    body.insert("secrets".into(), Value::String(secrets));

    make_request(
        &state,
        Operation::Write,
        format!("resource-group/groups/{name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_asset_group(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("resource-group/groups/{name}"),
        None,
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn list_asset_group_history(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<AssetGroupHistoryResult> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("resource-group/groups/{name}/history"),
        None,
    )
    .await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            let entries = data
                .and_then(|d| d.get("entries"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| {
                            let o = v.as_object()?;
                            Some(AssetGroupHistoryEntry {
                                ts: o.get("ts").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                user: o.get("user").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                op: o.get("op").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                changed_fields: o
                                    .get("changed_fields")
                                    .and_then(|x| x.as_array())
                                    .map(|a| {
                                        a.iter()
                                            .filter_map(|x| x.as_str().map(String::from))
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                                before: o
                                    .get("before")
                                    .and_then(|x| x.as_object())
                                    .cloned()
                                    .unwrap_or_default(),
                                after: o
                                    .get("after")
                                    .and_then(|x| x.as_object())
                                    .cloned()
                                    .unwrap_or_default(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(AssetGroupHistoryResult { entries })
        }
        None => Ok(AssetGroupHistoryResult { entries: vec![] }),
    }
}

/// List asset-groups that contain a given resource. Used for the
/// "Groups" chips on the Resources page.
#[tauri::command]
pub async fn asset_groups_for_resource(
    state: State<'_, AppState>,
    resource: String,
) -> CmdResult<AssetGroupLookupResult> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("resource-group/by-resource/{resource}"),
        None,
    )
    .await?;

    Ok(AssetGroupLookupResult {
        groups: data_string_list(resp.as_ref().and_then(|r| r.data.as_ref()), "groups"),
    })
}

/// List asset-groups that contain a given KV-secret path. The path is
/// base64url-encoded (no padding) on the wire so `/` segments in the
/// path don't clash with URL path separators.
#[tauri::command]
pub async fn asset_groups_for_secret(
    state: State<'_, AppState>,
    path: String,
) -> CmdResult<AssetGroupLookupResult> {
    let encoded = URL_SAFE_NO_PAD.encode(path.as_bytes());
    let resp = make_request(
        &state,
        Operation::Read,
        format!("resource-group/by-secret/{encoded}"),
        None,
    )
    .await?;

    Ok(AssetGroupLookupResult {
        groups: data_string_list(resp.as_ref().and_then(|r| r.data.as_ref()), "groups"),
    })
}
