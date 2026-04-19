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
pub struct GroupListResult {
    pub groups: Vec<String>,
}

#[derive(Serialize)]
pub struct GroupHistoryEntry {
    pub ts: String,
    pub user: String,
    pub op: String,
    pub changed_fields: Vec<String>,
    /// Field values before the change. Empty for `create`. Keys are a
    /// subset of {description, members, policies}; `description` is a
    /// string, `members` and `policies` are arrays of strings.
    pub before: Map<String, Value>,
    /// Field values after the change. Empty for `delete`.
    pub after: Map<String, Value>,
}

#[derive(Serialize)]
pub struct GroupHistoryResult {
    pub entries: Vec<GroupHistoryEntry>,
}

#[derive(Serialize)]
pub struct GroupInfo {
    pub name: String,
    pub kind: String,
    pub description: String,
    pub members: Vec<String>,
    pub policies: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

fn kind_segment(kind: &str) -> Result<&'static str, CommandError> {
    match kind {
        "user" => Ok("user"),
        "app" => Ok("app"),
        _ => Err("group kind must be 'user' or 'app'".into()),
    }
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
pub async fn list_groups(
    state: State<'_, AppState>,
    kind: String,
) -> CmdResult<GroupListResult> {
    let seg = kind_segment(&kind)?;
    let resp = make_request(
        &state,
        Operation::List,
        format!("identity/group/{seg}/"),
        None,
    )
    .await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let groups = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(GroupListResult { groups });
                }
            }
            Ok(GroupListResult { groups: vec![] })
        }
        None => Ok(GroupListResult { groups: vec![] }),
    }
}

#[tauri::command]
pub async fn read_group(
    state: State<'_, AppState>,
    kind: String,
    name: String,
) -> CmdResult<GroupInfo> {
    let seg = kind_segment(&kind)?;
    let resp = make_request(
        &state,
        Operation::Read,
        format!("identity/group/{seg}/{name}"),
        None,
    )
    .await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            Ok(GroupInfo {
                name: data
                    .and_then(|d| d.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&name)
                    .to_string(),
                kind: data
                    .and_then(|d| d.get("kind"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(seg)
                    .to_string(),
                description: data
                    .and_then(|d| d.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                members: data_string_list(data, "members"),
                policies: data_string_list(data, "policies"),
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
        None => Err("Group not found".into()),
    }
}

#[tauri::command]
pub async fn write_group(
    state: State<'_, AppState>,
    kind: String,
    name: String,
    description: String,
    members: String,
    policies: String,
) -> CmdResult<()> {
    let seg = kind_segment(&kind)?;
    let mut body = Map::new();
    body.insert("description".into(), Value::String(description));
    body.insert("members".into(), Value::String(members));
    body.insert("policies".into(), Value::String(policies));

    make_request(
        &state,
        Operation::Write,
        format!("identity/group/{seg}/{name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn list_group_history(
    state: State<'_, AppState>,
    kind: String,
    name: String,
) -> CmdResult<GroupHistoryResult> {
    let seg = kind_segment(&kind)?;
    let resp = make_request(
        &state,
        Operation::Read,
        format!("identity/group/{seg}/{name}/history"),
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
                            Some(GroupHistoryEntry {
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
            Ok(GroupHistoryResult { entries })
        }
        None => Ok(GroupHistoryResult { entries: vec![] }),
    }
}

#[tauri::command]
pub async fn delete_group(
    state: State<'_, AppState>,
    kind: String,
    name: String,
) -> CmdResult<()> {
    let seg = kind_segment(&kind)?;
    make_request(
        &state,
        Operation::Delete,
        format!("identity/group/{seg}/{name}"),
        None,
    )
    .await?;
    Ok(())
}
