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
pub struct PolicyListResult {
    pub policies: Vec<String>,
}

#[derive(Serialize)]
pub struct PolicyContent {
    pub name: String,
    pub policy: String,
}

#[derive(Serialize)]
pub struct PolicyHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    pub before_raw: String,
    pub after_raw: String,
}

#[derive(Serialize)]
pub struct PolicyHistoryResult {
    pub entries: Vec<PolicyHistoryEntry>,
}

#[tauri::command]
pub async fn list_policies(state: State<'_, AppState>) -> CmdResult<PolicyListResult> {
    let resp = make_request(&state, Operation::List, "sys/policies/acl/".to_string(), None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let policies: Vec<String> = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(PolicyListResult { policies });
                }
            }
            Ok(PolicyListResult { policies: vec![] })
        }
        None => Ok(PolicyListResult { policies: vec![] }),
    }
}

#[tauri::command]
pub async fn read_policy(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PolicyContent> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("sys/policies/acl/{name}"),
        None,
    )
    .await?;

    match resp {
        Some(r) => {
            let policy = r
                .data
                .as_ref()
                .and_then(|d| d.get("policy"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(PolicyContent { name, policy })
        }
        None => Err("Policy not found".into()),
    }
}

#[tauri::command]
pub async fn write_policy(
    state: State<'_, AppState>,
    name: String,
    policy: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("policy".to_string(), Value::String(policy));

    make_request(
        &state,
        Operation::Write,
        format!("sys/policies/acl/{name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn list_policy_history(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PolicyHistoryResult> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("sys/policies/acl/{name}/history"),
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
                            Some(PolicyHistoryEntry {
                                ts: o.get("ts").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                user: o.get("user").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                op: o.get("op").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                before_raw: o
                                    .get("before_raw")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                after_raw: o
                                    .get("after_raw")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(PolicyHistoryResult { entries })
        }
        None => Ok(PolicyHistoryResult { entries: vec![] }),
    }
}

#[tauri::command]
pub async fn delete_policy(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("sys/policies/acl/{name}"),
        None,
    )
    .await?;
    Ok(())
}
