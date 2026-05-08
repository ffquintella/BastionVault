use bv_client::Operation;
use serde::Serialize;
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

#[derive(Serialize)]
pub struct UserListResult {
    pub users: Vec<String>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub policies: Vec<String>,
}

#[tauri::command]
pub async fn list_users(
    state: State<'_, AppState>,
    mount_path: String,
) -> CmdResult<UserListResult> {
    let path = format!("auth/{mount_path}users/");
    let resp = make_request(&state, Operation::List, path, None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let users: Vec<String> = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(UserListResult { users });
                }
            }
            Ok(UserListResult { users: vec![] })
        }
        None => Ok(UserListResult { users: vec![] }),
    }
}

#[tauri::command]
pub async fn get_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
) -> CmdResult<UserInfo> {
    let path = format!("auth/{mount_path}users/{username}");
    let resp = make_request(&state, Operation::Read, path, None).await?;

    match resp {
        Some(r) => {
            let policies = r
                .data
                .as_ref()
                .and_then(|d| d.get("policies"))
                .map(|v| match v {
                    // Array of strings (from token_policies serialization)
                    Value::Array(arr) => arr
                        .iter()
                        .filter_map(|item| item.as_str().map(|s| s.trim().to_string()))
                        .filter(|s| !s.is_empty())
                        .collect(),
                    // Comma-separated string
                    Value::String(s) => s
                        .split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect(),
                    _ => vec![],
                })
                .unwrap_or_default();
            Ok(UserInfo {
                username,
                policies,
            })
        }
        None => Err("User not found".into()),
    }
}

#[tauri::command]
pub async fn create_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
    password: String,
    policies: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}");
    let mut body = Map::new();
    body.insert("password".to_string(), Value::String(password));
    if !policies.is_empty() {
        body.insert("policies".to_string(), Value::String(policies));
    }

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn update_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
    password: String,
    policies: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}");
    let mut body = Map::new();
    if !password.is_empty() {
        body.insert("password".to_string(), Value::String(password));
    }
    body.insert("policies".to_string(), Value::String(policies));

    make_request(&state, Operation::Write, path, Some(body)).await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_user(
    state: State<'_, AppState>,
    mount_path: String,
    username: String,
) -> CmdResult<()> {
    let path = format!("auth/{mount_path}users/{username}");
    make_request(&state, Operation::Delete, path, None).await?;
    Ok(())
}
